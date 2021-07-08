# Generated by default/object.tt
package Paws::AppRunner::SourceCodeVersion;
  use Moose;
  has Type => (is => 'ro', isa => 'Str', required => 1);
  has Value => (is => 'ro', isa => 'Str', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::AppRunner::SourceCodeVersion

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::AppRunner::SourceCodeVersion object:

  $service_obj->Method(Att1 => { Type => $value, ..., Value => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::AppRunner::SourceCodeVersion object:

  $result = $service_obj->Method(...);
  $result->Att1->Type

=head1 DESCRIPTION

Identifies a version of code that AWS App Runner refers to within a
source code repository.

=head1 ATTRIBUTES


=head2 B<REQUIRED> Type => Str

The type of version identifier.

For a git-based repository, branches represent versions.


=head2 B<REQUIRED> Value => Str

A source code version.

For a git-based repository, a branch name maps to a specific version.
App Runner uses the most recent commit to the branch.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::AppRunner>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

