# Generated by default/object.tt
package Paws::Honeycode::Table;
  use Moose;
  has TableId => (is => 'ro', isa => 'Str', request_name => 'tableId', traits => ['NameInRequest']);
  has TableName => (is => 'ro', isa => 'Str', request_name => 'tableName', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Honeycode::Table

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Honeycode::Table object:

  $service_obj->Method(Att1 => { TableId => $value, ..., TableName => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Honeycode::Table object:

  $result = $service_obj->Method(...);
  $result->Att1->TableId

=head1 DESCRIPTION

An object representing the properties of a table in a workbook.

=head1 ATTRIBUTES


=head2 TableId => Str

The id of the table.


=head2 TableName => Str

The name of the table.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Honeycode>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

