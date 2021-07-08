# Generated by default/object.tt
package Paws::Quicksight::FolderMember;
  use Moose;
  has MemberId => (is => 'ro', isa => 'Str');
  has MemberType => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::Quicksight::FolderMember

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Quicksight::FolderMember object:

  $service_obj->Method(Att1 => { MemberId => $value, ..., MemberType => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Quicksight::FolderMember object:

  $result = $service_obj->Method(...);
  $result->Att1->MemberId

=head1 DESCRIPTION

An asset in a folder, such as a dashboard, analysis, or dataset.

=head1 ATTRIBUTES


=head2 MemberId => Str

The ID of the asset.


=head2 MemberType => Str

The type of the asset.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Quicksight>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

